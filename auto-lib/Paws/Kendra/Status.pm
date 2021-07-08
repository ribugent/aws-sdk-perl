# Generated by default/object.tt
package Paws::Kendra::Status;
  use Moose;
  has DocumentId => (is => 'ro', isa => 'Str');
  has DocumentStatus => (is => 'ro', isa => 'Str');
  has FailureCode => (is => 'ro', isa => 'Str');
  has FailureReason => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::Kendra::Status

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Kendra::Status object:

  $service_obj->Method(Att1 => { DocumentId => $value, ..., FailureReason => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Kendra::Status object:

  $result = $service_obj->Method(...);
  $result->Att1->DocumentId

=head1 DESCRIPTION

Provides information about the status of documents submitted for
indexing.

=head1 ATTRIBUTES


=head2 DocumentId => Str

The unique identifier of the document.


=head2 DocumentStatus => Str

The current status of a document.

If the document was submitted for deletion, the status is C<NOT_FOUND>
after the document is deleted.


=head2 FailureCode => Str

Indicates the source of the error.


=head2 FailureReason => Str

Provides detailed information about why the document couldn't be
indexed. Use this information to correct the error before you resubmit
the document for indexing.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Kendra>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

