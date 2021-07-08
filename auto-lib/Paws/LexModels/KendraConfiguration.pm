# Generated by default/object.tt
package Paws::LexModels::KendraConfiguration;
  use Moose;
  has KendraIndex => (is => 'ro', isa => 'Str', request_name => 'kendraIndex', traits => ['NameInRequest'], required => 1);
  has QueryFilterString => (is => 'ro', isa => 'Str', request_name => 'queryFilterString', traits => ['NameInRequest']);
  has Role => (is => 'ro', isa => 'Str', request_name => 'role', traits => ['NameInRequest'], required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::LexModels::KendraConfiguration

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::LexModels::KendraConfiguration object:

  $service_obj->Method(Att1 => { KendraIndex => $value, ..., Role => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::LexModels::KendraConfiguration object:

  $result = $service_obj->Method(...);
  $result->Att1->KendraIndex

=head1 DESCRIPTION

Provides configuration information for the AMAZON.KendraSearchIntent
intent. When you use this intent, Amazon Lex searches the specified
Amazon Kendra index and returns documents from the index that match the
user's utterance. For more information, see AMAZON.KendraSearchIntent
(http://docs.aws.amazon.com/lex/latest/dg/built-in-intent-kendra-search.html).

=head1 ATTRIBUTES


=head2 B<REQUIRED> KendraIndex => Str

The Amazon Resource Name (ARN) of the Amazon Kendra index that you want
the AMAZON.KendraSearchIntent intent to search. The index must be in
the same account and Region as the Amazon Lex bot. If the Amazon Kendra
index does not exist, you get an exception when you call the
C<PutIntent> operation.


=head2 QueryFilterString => Str

A query filter that Amazon Lex sends to Amazon Kendra to filter the
response from the query. The filter is in the format defined by Amazon
Kendra. For more information, see Filtering queries
(http://docs.aws.amazon.com/kendra/latest/dg/filtering.html).

You can override this filter string with a new filter string at
runtime.


=head2 B<REQUIRED> Role => Str

The Amazon Resource Name (ARN) of an IAM role that has permission to
search the Amazon Kendra index. The role must be in the same account
and Region as the Amazon Lex bot. If the role does not exist, you get
an exception when you call the C<PutIntent> operation.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::LexModels>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

