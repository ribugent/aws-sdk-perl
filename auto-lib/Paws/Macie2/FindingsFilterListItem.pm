# Generated by default/object.tt
package Paws::Macie2::FindingsFilterListItem;
  use Moose;
  has Action => (is => 'ro', isa => 'Str', request_name => 'action', traits => ['NameInRequest']);
  has Arn => (is => 'ro', isa => 'Str', request_name => 'arn', traits => ['NameInRequest']);
  has Id => (is => 'ro', isa => 'Str', request_name => 'id', traits => ['NameInRequest']);
  has Name => (is => 'ro', isa => 'Str', request_name => 'name', traits => ['NameInRequest']);
  has Tags => (is => 'ro', isa => 'Paws::Macie2::TagMap', request_name => 'tags', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Macie2::FindingsFilterListItem

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Macie2::FindingsFilterListItem object:

  $service_obj->Method(Att1 => { Action => $value, ..., Tags => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Macie2::FindingsFilterListItem object:

  $result = $service_obj->Method(...);
  $result->Att1->Action

=head1 DESCRIPTION

Provides information about a findings filter.

=head1 ATTRIBUTES


=head2 Action => Str

The action that's performed on findings that meet the filter criteria.
Possible values are: ARCHIVE, suppress (automatically archive) the
findings; and, NOOP, don't perform any action on the findings.


=head2 Arn => Str

The Amazon Resource Name (ARN) of the filter.


=head2 Id => Str

The unique identifier for the filter.


=head2 Name => Str

The custom name of the filter.


=head2 Tags => L<Paws::Macie2::TagMap>

A map of key-value pairs that identifies the tags (keys and values)
that are associated with the filter.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Macie2>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

